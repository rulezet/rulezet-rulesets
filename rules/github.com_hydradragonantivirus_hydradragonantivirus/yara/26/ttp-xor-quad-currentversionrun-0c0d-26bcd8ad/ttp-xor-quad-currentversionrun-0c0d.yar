rule TTP_XOR_QUAD_CurrentVersionRun_0c0d {
  strings:
    $key_0c0d = { 5f 62 [2] 7b 6c [2] 50 40 [2] 7e 62 [2] 6a 79 [2] 65 63 [2] 7b 7e [2] 79 7f [2] 62 79 [2] 7e 7e [2] 62 51 }

  condition:
    any of them
}