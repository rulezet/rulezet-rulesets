rule TTP_XOR_QUAD_CurrentVersionRun_480f {
  strings:
    $key_480f = { 1b 60 [2] 3f 6e [2] 14 42 [2] 3a 60 [2] 2e 7b [2] 21 61 [2] 3f 7c [2] 3d 7d [2] 26 7b [2] 3a 7c [2] 26 53 }

  condition:
    any of them
}