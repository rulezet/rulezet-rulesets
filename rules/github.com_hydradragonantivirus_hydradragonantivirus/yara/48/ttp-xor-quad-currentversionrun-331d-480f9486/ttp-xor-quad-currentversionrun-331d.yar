rule TTP_XOR_QUAD_CurrentVersionRun_331d {
  strings:
    $key_331d = { 60 72 [2] 44 7c [2] 6f 50 [2] 41 72 [2] 55 69 [2] 5a 73 [2] 44 6e [2] 46 6f [2] 5d 69 [2] 41 6e [2] 5d 41 }

  condition:
    any of them
}