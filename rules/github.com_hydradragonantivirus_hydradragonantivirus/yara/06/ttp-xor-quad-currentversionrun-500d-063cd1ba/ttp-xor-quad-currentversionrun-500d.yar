rule TTP_XOR_QUAD_CurrentVersionRun_500d {
  strings:
    $key_500d = { 03 62 [2] 27 6c [2] 0c 40 [2] 22 62 [2] 36 79 [2] 39 63 [2] 27 7e [2] 25 7f [2] 3e 79 [2] 22 7e [2] 3e 51 }

  condition:
    any of them
}