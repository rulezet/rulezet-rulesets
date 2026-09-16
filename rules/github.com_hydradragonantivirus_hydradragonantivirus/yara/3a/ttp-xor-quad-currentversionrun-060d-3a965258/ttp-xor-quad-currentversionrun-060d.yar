rule TTP_XOR_QUAD_CurrentVersionRun_060d {
  strings:
    $key_060d = { 55 62 [2] 71 6c [2] 5a 40 [2] 74 62 [2] 60 79 [2] 6f 63 [2] 71 7e [2] 73 7f [2] 68 79 [2] 74 7e [2] 68 51 }

  condition:
    any of them
}