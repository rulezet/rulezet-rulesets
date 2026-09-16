rule TTP_XOR_QUAD_CurrentVersionRun_064f {
  strings:
    $key_064f = { 55 20 [2] 71 2e [2] 5a 02 [2] 74 20 [2] 60 3b [2] 6f 21 [2] 71 3c [2] 73 3d [2] 68 3b [2] 74 3c [2] 68 13 }

  condition:
    any of them
}