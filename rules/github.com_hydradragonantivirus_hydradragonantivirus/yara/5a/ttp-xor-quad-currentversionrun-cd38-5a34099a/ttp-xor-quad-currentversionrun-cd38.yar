rule TTP_XOR_QUAD_CurrentVersionRun_cd38 {
  strings:
    $key_cd38 = { 9e 57 [2] ba 59 [2] 91 75 [2] bf 57 [2] ab 4c [2] a4 56 [2] ba 4b [2] b8 4a [2] a3 4c [2] bf 4b [2] a3 64 }

  condition:
    any of them
}