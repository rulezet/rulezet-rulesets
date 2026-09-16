rule TTP_XOR_QUAD_CurrentVersionRun_ca3d {
  strings:
    $key_ca3d = { 99 52 [2] bd 5c [2] 96 70 [2] b8 52 [2] ac 49 [2] a3 53 [2] bd 4e [2] bf 4f [2] a4 49 [2] b8 4e [2] a4 61 }

  condition:
    any of them
}