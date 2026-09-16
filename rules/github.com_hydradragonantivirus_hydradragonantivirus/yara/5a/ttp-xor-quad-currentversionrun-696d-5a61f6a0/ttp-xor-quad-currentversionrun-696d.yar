rule TTP_XOR_QUAD_CurrentVersionRun_696d {
  strings:
    $key_696d = { 3a 02 [2] 1e 0c [2] 35 20 [2] 1b 02 [2] 0f 19 [2] 00 03 [2] 1e 1e [2] 1c 1f [2] 07 19 [2] 1b 1e [2] 07 31 }

  condition:
    any of them
}