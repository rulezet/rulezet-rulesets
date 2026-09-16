rule TTP_XOR_QUAD_CurrentVersionRun_cf3f {
  strings:
    $key_cf3f = { 9c 50 [2] b8 5e [2] 93 72 [2] bd 50 [2] a9 4b [2] a6 51 [2] b8 4c [2] ba 4d [2] a1 4b [2] bd 4c [2] a1 63 }

  condition:
    any of them
}