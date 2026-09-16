rule TTP_XOR_QUAD_CurrentVersionRun_341d {
  strings:
    $key_341d = { 67 72 [2] 43 7c [2] 68 50 [2] 46 72 [2] 52 69 [2] 5d 73 [2] 43 6e [2] 41 6f [2] 5a 69 [2] 46 6e [2] 5a 41 }

  condition:
    any of them
}