rule AtomTable_Inject {
  meta:
    Author      = "Thomas Roccia - @fr0gger_ - Unprotect Project"
    Description = " Detect AtomBombing technique"

  strings:
    $var1 = "GlobalAddAtom"
    $var2 = "GlobalGetAtomName"
    $var3 = "QueueUserAPC"

  condition:
    all of them
}