rule TTP_XOR_QUAD_CurrentVersionRun_574c {
  strings:
    $key_574c = { 04 23 [2] 20 2d [2] 0b 01 [2] 25 23 [2] 31 38 [2] 3e 22 [2] 20 3f [2] 22 3e [2] 39 38 [2] 25 3f [2] 39 10 }

  condition:
    any of them
}