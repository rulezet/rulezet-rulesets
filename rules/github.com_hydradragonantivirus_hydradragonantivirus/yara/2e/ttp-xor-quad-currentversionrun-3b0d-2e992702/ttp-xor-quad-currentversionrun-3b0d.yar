rule TTP_XOR_QUAD_CurrentVersionRun_3b0d {
  strings:
    $key_3b0d = { 68 62 [2] 4c 6c [2] 67 40 [2] 49 62 [2] 5d 79 [2] 52 63 [2] 4c 7e [2] 4e 7f [2] 55 79 [2] 49 7e [2] 55 51 }

  condition:
    any of them
}