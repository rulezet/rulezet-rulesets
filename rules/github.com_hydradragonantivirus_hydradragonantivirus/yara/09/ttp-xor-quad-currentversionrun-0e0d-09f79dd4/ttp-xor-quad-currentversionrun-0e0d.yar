rule TTP_XOR_QUAD_CurrentVersionRun_0e0d {
  strings:
    $key_0e0d = { 5d 62 [2] 79 6c [2] 52 40 [2] 7c 62 [2] 68 79 [2] 67 63 [2] 79 7e [2] 7b 7f [2] 60 79 [2] 7c 7e [2] 60 51 }

  condition:
    any of them
}