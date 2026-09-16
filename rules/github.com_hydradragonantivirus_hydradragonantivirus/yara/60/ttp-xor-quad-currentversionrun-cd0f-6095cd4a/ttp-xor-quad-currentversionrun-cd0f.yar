rule TTP_XOR_QUAD_CurrentVersionRun_cd0f {
  strings:
    $key_cd0f = { 9e 60 [2] ba 6e [2] 91 42 [2] bf 60 [2] ab 7b [2] a4 61 [2] ba 7c [2] b8 7d [2] a3 7b [2] bf 7c [2] a3 53 }

  condition:
    any of them
}