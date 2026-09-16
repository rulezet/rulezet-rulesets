rule TTP_XOR_QUAD_CurrentVersionRun_cba2 {
  strings:
    $key_cba2 = { 98 cd [2] bc c3 [2] 97 ef [2] b9 cd [2] ad d6 [2] a2 cc [2] bc d1 [2] be d0 [2] a5 d6 [2] b9 d1 [2] a5 fe }

  condition:
    any of them
}