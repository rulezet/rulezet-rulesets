rule TTP_XOR_QUAD_CurrentVersionRun_304f {
  strings:
    $key_304f = { 63 20 [2] 47 2e [2] 6c 02 [2] 42 20 [2] 56 3b [2] 59 21 [2] 47 3c [2] 45 3d [2] 5e 3b [2] 42 3c [2] 5e 13 }

  condition:
    any of them
}