rule self_inject : suspicious feature dll injection windows
{
meta:
        description = "Self Injecting code - like code packers"
        link = ""

strings:
        	$self01 = "VirtualAlloc"
        	$self02 = "VirtualProtect"
                $self03 = "CreateProcessInternal"

condition:
	        uint16be(0) == 0x4d5a and
        all of them
}