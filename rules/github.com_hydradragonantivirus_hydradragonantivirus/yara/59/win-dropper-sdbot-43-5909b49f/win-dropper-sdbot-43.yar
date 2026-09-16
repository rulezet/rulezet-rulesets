rule Win_Dropper_SdBot_43
{
strings:
	$a0 = { fdbffcdfe8ffd002b2747874496e636f6d07670e2b8f34dd1f4f0b1dfeffff2f63012134034f75742fdd79c8676f680169146d4952aa5beadd437c37fe1bb5233e648b05345ebd50bb248857ffffffff530b }


condition:
	$a0
}