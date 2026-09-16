rule TTP_XOR_QUAD_CurrentVersionRun_3db1 {
  strings:
    $key_3db1 = { 6e de [2] 4a d0 [2] 61 fc [2] 4f de [2] 5b c5 [2] 54 df [2] 4a c2 [2] 48 c3 [2] 53 c5 [2] 4f c2 [2] 53 ed }

  condition:
    any of them
}