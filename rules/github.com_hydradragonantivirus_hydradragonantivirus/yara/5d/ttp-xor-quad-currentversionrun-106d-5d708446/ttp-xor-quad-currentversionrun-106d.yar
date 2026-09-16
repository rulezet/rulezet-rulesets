rule TTP_XOR_QUAD_CurrentVersionRun_106d {
  strings:
    $key_106d = { 43 02 [2] 67 0c [2] 4c 20 [2] 62 02 [2] 76 19 [2] 79 03 [2] 67 1e [2] 65 1f [2] 7e 19 [2] 62 1e [2] 7e 31 }

  condition:
    any of them
}