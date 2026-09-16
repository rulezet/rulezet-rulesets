rule TTP_XOR_QUAD_CurrentVersionRun_dda2 {
  strings:
    $key_dda2 = { 8e cd [2] aa c3 [2] 81 ef [2] af cd [2] bb d6 [2] b4 cc [2] aa d1 [2] a8 d0 [2] b3 d6 [2] af d1 [2] b3 fe }

  condition:
    any of them
}