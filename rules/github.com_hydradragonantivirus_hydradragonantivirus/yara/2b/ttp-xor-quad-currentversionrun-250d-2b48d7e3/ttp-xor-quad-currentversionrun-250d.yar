rule TTP_XOR_QUAD_CurrentVersionRun_250d {
  strings:
    $key_250d = { 76 62 [2] 52 6c [2] 79 40 [2] 57 62 [2] 43 79 [2] 4c 63 [2] 52 7e [2] 50 7f [2] 4b 79 [2] 57 7e [2] 4b 51 }

  condition:
    any of them
}