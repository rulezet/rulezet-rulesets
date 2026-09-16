rule TTP_XOR_QUAD_CurrentVersionRun_dcb1 {
  strings:
    $key_dcb1 = { 8f de [2] ab d0 [2] 80 fc [2] ae de [2] ba c5 [2] b5 df [2] ab c2 [2] a9 c3 [2] b2 c5 [2] ae c2 [2] b2 ed }

  condition:
    any of them
}