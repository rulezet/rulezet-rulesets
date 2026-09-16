rule TTP_XOR_QUAD_CurrentVersionRun_031d {
  strings:
    $key_031d = { 50 72 [2] 74 7c [2] 5f 50 [2] 71 72 [2] 65 69 [2] 6a 73 [2] 74 6e [2] 76 6f [2] 6d 69 [2] 71 6e [2] 6d 41 }

  condition:
    any of them
}