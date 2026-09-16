rule TTP_XOR_QUAD_CurrentVersionRun_c2a2 {
  strings:
    $key_c2a2 = { 91 cd [2] b5 c3 [2] 9e ef [2] b0 cd [2] a4 d6 [2] ab cc [2] b5 d1 [2] b7 d0 [2] ac d6 [2] b0 d1 [2] ac fe }

  condition:
    any of them
}