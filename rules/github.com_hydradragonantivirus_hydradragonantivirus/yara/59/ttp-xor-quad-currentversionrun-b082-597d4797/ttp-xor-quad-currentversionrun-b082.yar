rule TTP_XOR_QUAD_CurrentVersionRun_b082 {
  strings:
    $key_b082 = { e3 ed [2] c7 e3 [2] ec cf [2] c2 ed [2] d6 f6 [2] d9 ec [2] c7 f1 [2] c5 f0 [2] de f6 [2] c2 f1 [2] de de }

  condition:
    any of them
}