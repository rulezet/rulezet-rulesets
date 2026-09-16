rule TTP_XOR_QUAD_CurrentVersionRun_75e3 {
  strings:
    $key_75e3 = { 26 8c [2] 02 82 [2] 29 ae [2] 07 8c [2] 13 97 [2] 1c 8d [2] 02 90 [2] 00 91 [2] 1b 97 [2] 07 90 [2] 1b bf }

  condition:
    any of them
}