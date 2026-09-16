rule TTP_XOR_QUAD_CurrentVersionRun_231d {
  strings:
    $key_231d = { 70 72 [2] 54 7c [2] 7f 50 [2] 51 72 [2] 45 69 [2] 4a 73 [2] 54 6e [2] 56 6f [2] 4d 69 [2] 51 6e [2] 4d 41 }

  condition:
    any of them
}