rule TTP_XOR_QUAD_CurrentVersionRun_031f {
  strings:
    $key_031f = { 50 70 [2] 74 7e [2] 5f 52 [2] 71 70 [2] 65 6b [2] 6a 71 [2] 74 6c [2] 76 6d [2] 6d 6b [2] 71 6c [2] 6d 43 }

  condition:
    any of them
}