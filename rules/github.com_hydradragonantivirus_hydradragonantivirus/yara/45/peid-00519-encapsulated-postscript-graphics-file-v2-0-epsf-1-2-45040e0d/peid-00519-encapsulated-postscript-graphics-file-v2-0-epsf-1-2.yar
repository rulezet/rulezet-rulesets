rule PEiD_00519_Encapsulated_Postscript_graphics_file_v2_0_EPSF_1_2_ {
  meta:
    description = "[Encapsulated Postscript graphics file v2.0 EPSF-1.2]"
    ep_only     = "false"

  strings:
    $a = "%!PS-Adobe-2.0 EPSF-1.2"

  condition:
    $a
}