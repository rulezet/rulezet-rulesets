rule TTP_XOR_QUAD_CurrentVersionRun_0a4f {
  strings:
    $key_0a4f = { 59 20 [2] 7d 2e [2] 56 02 [2] 78 20 [2] 6c 3b [2] 63 21 [2] 7d 3c [2] 7f 3d [2] 64 3b [2] 78 3c [2] 64 13 }

  condition:
    any of them
}