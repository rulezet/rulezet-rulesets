rule TTP_XOR_QUAD_CurrentVersionRun_d9b1 {
  strings:
    $key_d9b1 = { 8a de [2] ae d0 [2] 85 fc [2] ab de [2] bf c5 [2] b0 df [2] ae c2 [2] ac c3 [2] b7 c5 [2] ab c2 [2] b7 ed }

  condition:
    any of them
}