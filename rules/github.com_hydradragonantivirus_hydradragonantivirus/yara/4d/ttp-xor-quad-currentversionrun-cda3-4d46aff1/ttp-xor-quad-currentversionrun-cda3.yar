rule TTP_XOR_QUAD_CurrentVersionRun_cda3 {
  strings:
    $key_cda3 = { 9e cc [2] ba c2 [2] 91 ee [2] bf cc [2] ab d7 [2] a4 cd [2] ba d0 [2] b8 d1 [2] a3 d7 [2] bf d0 [2] a3 ff }

  condition:
    any of them
}