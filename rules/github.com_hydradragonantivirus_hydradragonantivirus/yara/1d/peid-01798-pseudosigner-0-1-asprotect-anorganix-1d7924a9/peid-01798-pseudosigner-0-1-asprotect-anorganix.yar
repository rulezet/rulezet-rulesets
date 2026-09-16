rule PEiD_01798_PseudoSigner_0_1__ASProtect_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [ASProtect] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9 }

  condition:
    $a
}