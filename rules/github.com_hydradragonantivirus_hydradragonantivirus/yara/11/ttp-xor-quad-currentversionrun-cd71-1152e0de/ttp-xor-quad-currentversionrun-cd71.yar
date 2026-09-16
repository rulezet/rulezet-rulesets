rule TTP_XOR_QUAD_CurrentVersionRun_cd71 {
  strings:
    $key_cd71 = { 9e 1e [2] ba 10 [2] 91 3c [2] bf 1e [2] ab 05 [2] a4 1f [2] ba 02 [2] b8 03 [2] a3 05 [2] bf 02 [2] a3 2d }

  condition:
    any of them
}