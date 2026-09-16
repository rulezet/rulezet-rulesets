rule TTP_XOR_QUAD_CurrentVersionRun_0c0c {
  strings:
    $key_0c0c = { 5f 63 [2] 7b 6d [2] 50 41 [2] 7e 63 [2] 6a 78 [2] 65 62 [2] 7b 7f [2] 79 7e [2] 62 78 [2] 7e 7f [2] 62 50 }

  condition:
    any of them
}