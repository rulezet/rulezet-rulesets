rule TTP_XOR_QUAD_CurrentVersionRun_1db1 {
  strings:
    $key_1db1 = { 4e de [2] 6a d0 [2] 41 fc [2] 6f de [2] 7b c5 [2] 74 df [2] 6a c2 [2] 68 c3 [2] 73 c5 [2] 6f c2 [2] 73 ed }

  condition:
    any of them
}