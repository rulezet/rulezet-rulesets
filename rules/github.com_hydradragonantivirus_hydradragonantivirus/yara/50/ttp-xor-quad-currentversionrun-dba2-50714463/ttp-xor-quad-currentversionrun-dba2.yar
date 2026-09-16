rule TTP_XOR_QUAD_CurrentVersionRun_dba2 {
  strings:
    $key_dba2 = { 88 cd [2] ac c3 [2] 87 ef [2] a9 cd [2] bd d6 [2] b2 cc [2] ac d1 [2] ae d0 [2] b5 d6 [2] a9 d1 [2] b5 fe }

  condition:
    any of them
}