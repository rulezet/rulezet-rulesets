rule TTP_XOR_QUAD_CurrentVersionRun_a582 {
  strings:
    $key_a582 = { f6 ed [2] d2 e3 [2] f9 cf [2] d7 ed [2] c3 f6 [2] cc ec [2] d2 f1 [2] d0 f0 [2] cb f6 [2] d7 f1 [2] cb de }

  condition:
    any of them
}