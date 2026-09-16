rule TTP_XOR_QUAD_CurrentVersionRun_111f {
  strings:
    $key_111f = { 42 70 [2] 66 7e [2] 4d 52 [2] 63 70 [2] 77 6b [2] 78 71 [2] 66 6c [2] 64 6d [2] 7f 6b [2] 63 6c [2] 7f 43 }

  condition:
    any of them
}