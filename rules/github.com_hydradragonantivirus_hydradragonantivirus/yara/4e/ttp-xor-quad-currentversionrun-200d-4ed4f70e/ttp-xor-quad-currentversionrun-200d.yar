rule TTP_XOR_QUAD_CurrentVersionRun_200d {
  strings:
    $key_200d = { 73 62 [2] 57 6c [2] 7c 40 [2] 52 62 [2] 46 79 [2] 49 63 [2] 57 7e [2] 55 7f [2] 4e 79 [2] 52 7e [2] 4e 51 }

  condition:
    any of them
}