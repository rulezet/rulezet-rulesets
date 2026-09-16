rule TTP_XOR_QUAD_CurrentVersionRun_3b4f {
  strings:
    $key_3b4f = { 68 20 [2] 4c 2e [2] 67 02 [2] 49 20 [2] 5d 3b [2] 52 21 [2] 4c 3c [2] 4e 3d [2] 55 3b [2] 49 3c [2] 55 13 }

  condition:
    any of them
}