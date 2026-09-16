rule Win_Adware_Lop_206
{
strings:
	$a0 = { e155139a0265a8b118fd18049dbc383db026bb4e108c9814accd985dc831e242bb9ce7140b8f23e94e0e8220c996cb24d35f5933961b08ee7fca951d }


condition:
	$a0
}