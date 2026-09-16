rule TTP_XOR_QUAD_CurrentVersionRun_2b4f {
  strings:
    $key_2b4f = { 78 20 [2] 5c 2e [2] 77 02 [2] 59 20 [2] 4d 3b [2] 42 21 [2] 5c 3c [2] 5e 3d [2] 45 3b [2] 59 3c [2] 45 13 }

  condition:
    any of them
}