rule TTP_XOR_QUAD_CurrentVersionRun_331c {
  strings:
    $key_331c = { 60 73 [2] 44 7d [2] 6f 51 [2] 41 73 [2] 55 68 [2] 5a 72 [2] 44 6f [2] 46 6e [2] 5d 68 [2] 41 6f [2] 5d 40 }

  condition:
    any of them
}