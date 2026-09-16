rule TTP_XOR_QUAD_CurrentVersionRun_696c {
  strings:
    $key_696c = { 3a 03 [2] 1e 0d [2] 35 21 [2] 1b 03 [2] 0f 18 [2] 00 02 [2] 1e 1f [2] 1c 1e [2] 07 18 [2] 1b 1f [2] 07 30 }

  condition:
    any of them
}