rule TTP_XOR_QUAD_CurrentVersionRun_de3d {
  strings:
    $key_de3d = { 8d 52 [2] a9 5c [2] 82 70 [2] ac 52 [2] b8 49 [2] b7 53 [2] a9 4e [2] ab 4f [2] b0 49 [2] ac 4e [2] b0 61 }

  condition:
    any of them
}