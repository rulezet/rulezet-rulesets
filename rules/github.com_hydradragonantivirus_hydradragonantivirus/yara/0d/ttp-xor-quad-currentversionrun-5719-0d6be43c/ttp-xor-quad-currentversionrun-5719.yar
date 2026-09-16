rule TTP_XOR_QUAD_CurrentVersionRun_5719 {
  strings:
    $key_5719 = { 04 76 [2] 20 78 [2] 0b 54 [2] 25 76 [2] 31 6d [2] 3e 77 [2] 20 6a [2] 22 6b [2] 39 6d [2] 25 6a [2] 39 45 }

  condition:
    any of them
}