rule TTP_XOR_QUAD_CurrentVersionRun_cd22 {
  strings:
    $key_cd22 = { 9e 4d [2] ba 43 [2] 91 6f [2] bf 4d [2] ab 56 [2] a4 4c [2] ba 51 [2] b8 50 [2] a3 56 [2] bf 51 [2] a3 7e }

  condition:
    any of them
}