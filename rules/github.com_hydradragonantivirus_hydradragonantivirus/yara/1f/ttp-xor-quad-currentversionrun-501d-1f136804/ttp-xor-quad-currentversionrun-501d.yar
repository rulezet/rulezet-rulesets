rule TTP_XOR_QUAD_CurrentVersionRun_501d {
  strings:
    $key_501d = { 03 72 [2] 27 7c [2] 0c 50 [2] 22 72 [2] 36 69 [2] 39 73 [2] 27 6e [2] 25 6f [2] 3e 69 [2] 22 6e [2] 3e 41 }

  condition:
    any of them
}