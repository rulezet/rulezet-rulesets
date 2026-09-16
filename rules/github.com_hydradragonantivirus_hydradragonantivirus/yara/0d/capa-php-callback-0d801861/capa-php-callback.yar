rule capa_php_callback: WEBSHELL PROD {
  meta:
    description = "PHP functions which accept callback functions to execute, in plain text"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/14"

  strings:
    $callback1  = /\bob_start[\t ]*\([^)]/ nocase wide ascii
    $callback2  = /\barray_diff_uassoc[\t ]*\([^)]/ nocase wide ascii
    $callback3  = /\barray_diff_ukey[\t ]*\([^)]/ nocase wide ascii
    $callback4  = /\barray_filter[\t ]*\([^)]/ nocase wide ascii
    $callback5  = /\barray_intersect_uassoc[\t ]*\([^)]/ nocase wide ascii
    $callback6  = /\barray_intersect_ukey[\t ]*\([^)]/ nocase wide ascii
    $callback7  = /\barray_map[\t ]*\([^)]/ nocase wide ascii
    $callback8  = /\barray_reduce[\t ]*\([^)]/ nocase wide ascii
    $callback9  = /\barray_udiff_assoc[\t ]*\([^)]/ nocase wide ascii
    $callback10 = /\barray_udiff_uassoc[\t ]*\([^)]/ nocase wide ascii
    $callback11 = /\barray_udiff[\t ]*\([^)]/ nocase wide ascii
    $callback12 = /\barray_uintersect_assoc[\t ]*\([^)]/ nocase wide ascii
    $callback13 = /\barray_uintersect_uassoc[\t ]*\([^)]/ nocase wide ascii
    $callback14 = /\barray_uintersect[\t ]*\([^)]/ nocase wide ascii
    $callback15 = /\barray_walk_recursive[\t ]*\([^)]/ nocase wide ascii
    $callback16 = /\barray_walk[\t ]*\([^)]/ nocase wide ascii
    $callback17 = /\bassert_options[\t ]*\([^)]/ nocase wide ascii
    $callback18 = /\buasort[\t ]*\([^)]/ nocase wide ascii
    $callback19 = /\buksort[\t ]*\([^)]/ nocase wide ascii
    $callback20 = /\busort[\t ]*\([^)]/ nocase wide ascii
    $callback21 = /\bpreg_replace_callback[\t ]*\([^)]/ nocase wide ascii
    $callback22 = /\bspl_autoload_register[\t ]*\([^)]/ nocase wide ascii
    $callback23 = /\biterator_apply[\t ]*\([^)]/ nocase wide ascii
    $callback24 = /\bcall_user_func[\t ]*\([^)]/ nocase wide ascii
    $callback25 = /\bcall_user_func_array[\t ]*\([^)]/ nocase wide ascii
    $callback26 = /\bregister_shutdown_function[\t ]*\([^)]/ nocase wide ascii
    $callback27 = /\bregister_tick_function[\t ]*\([^)]/ nocase wide ascii
    $callback28 = /\bset_error_handler[\t ]*\([^)]/ nocase wide ascii
    $callback29 = /\bset_exception_handler[\t ]*\([^)]/ nocase wide ascii
    $callback30 = /\bsession_set_save_handler[\t ]*\([^)]/ nocase wide ascii
    $callback31 = /\bsqlite_create_aggregate[\t ]*\([^)]/ nocase wide ascii
    $callback32 = /\bsqlite_create_function[\t ]*\([^)]/ nocase wide ascii
    $callback33 = /\bmb_ereg_replace_callback[\t ]*\([^)]/ nocase wide ascii

    $m_callback1 = /\bfilter_var[\t ]*\([^)]/ nocase wide ascii
    $m_callback2 = "FILTER_CALLBACK" fullword wide ascii

    $cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
    $cfp2 = "IWPML_Backend_Action_Loader" ascii wide
    $cfp3 = "<?phpclass WPML" ascii

  condition:
    not any of ($cfp*) and
    (
      any of ($callback*) or
      all of ($m_callback*)
    )
}